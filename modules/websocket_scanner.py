#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - WebSocket Scanner
فحص WebSocket endpoints

الميزات:
1. كشف WebSocket endpoints
2. فحص authentication
3. فحص Origin validation
4. Test message injection
5. كشف sensitive data
"""
import os
import sys
import re
import socket
import ssl
import hashlib
import base64
from typing import Dict, List, Optional
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


class WebSocketScanner:
    """فحص WebSocket"""

    def __init__(self, http_client: HttpClient = None, audit_logger=None):
        self.client = http_client or HttpClient(timeout=10)
        self.audit = audit_logger
        self.logger = SmartLogger()
        self.findings = []

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[WEBSOCKET] {msg}", level)

    def scan(self, url: str) -> Dict:
        """فحص WebSocket للموقع"""
        self._log(f"فحص WebSocket لـ: {url}", "phase")

        result = {
            "ws_endpoints": [],
            "vulnerabilities": [],
        }

        # 1) كشف WebSocket endpoints في HTML
        ws_urls = self._detect_ws_in_html(url)
        
        # 2) كشف في JavaScript
        js_urls = self._detect_ws_in_js(url)
        
        all_ws = set(ws_urls + js_urls)

        if not all_ws:
            self._log("لم يتم العثور على WebSocket endpoints", "info")
            return result

        self._log(f"تم العثور على {len(all_ws)} WebSocket endpoint", "success")

        # 3) فحص كل endpoint
        for ws_url in all_ws:
            ws_info = self._analyze_ws_endpoint(ws_url, url)
            result["ws_endpoints"].append(ws_info)
            
            # فحص الثغرات
            vulns = self._check_ws_vulns(ws_url, url)
            result["vulnerabilities"].extend(vulns)

        self._print_results(result)
        return result

    def _detect_ws_in_html(self, url: str) -> List[str]:
        """كشف WebSocket في HTML"""
        ws_urls = []
        resp = self.client.get(url)
        
        if resp["status"] == 0:
            return ws_urls

        # patterns
        patterns = [
            r'["\'](?:ws|wss)://([^"\']+)["\']',
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'["\'](/ws/[^"\']+)["\']',
            r'["\'](/socket\.io/[^"\']+)["\']',
        ]

        for pattern in patterns:
            matches = re.findall(pattern, resp["body"])
            for match in matches:
                if match.startswith("ws://") or match.startswith("wss://"):
                    ws_urls.append(match)
                elif match.startswith("/"):
                    parsed = urlparse(url)
                    ws_urls.append(f"wss://{parsed.netloc}{match}")

        return list(set(ws_urls))

    def _detect_ws_in_js(self, url: str) -> List[str]:
        """كشف WebSocket في JavaScript files"""
        ws_urls = []

        # تحليل JS (بسيط)
        resp = self.client.get(url)
        if resp["status"] == 0:
            return ws_urls

        # استخراج JS files
        js_pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
        js_files = re.findall(js_pattern, resp["body"], re.IGNORECASE)

        from urllib.parse import urljoin
        for js_file in js_files[:10]:
            js_url = urljoin(url, js_file)
            js_resp = self.client.get(js_url)
            
            if js_resp["status"] == 200:
                # البحث عن WebSocket
                patterns = [
                    r'["\'](?:ws|wss)://([^"\']+)["\']',
                    r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, js_resp["body"])
                    for match in matches:
                        if match.startswith("ws://") or match.startswith("wss://"):
                            ws_urls.append(match)
                        elif match.startswith("/"):
                            parsed = urlparse(url)
                            ws_urls.append(f"wss://{parsed.netloc}{match}")

        return list(set(ws_urls))

    def _analyze_ws_endpoint(self, ws_url: str, source_url: str) -> Dict:
        """تحليل WebSocket endpoint"""
        info = {
            "url": ws_url,
            "source": source_url,
            "secure": ws_url.startswith("wss://"),
            "accessible": False,
        }

        # محاولة الاتصال (TCP level)
        try:
            parsed = urlparse(ws_url.replace("ws://", "http://").replace("wss://", "https://"))
            host = parsed.hostname
            port = parsed.port or (443 if ws_url.startswith("wss://") else 80)

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()

            info["accessible"] = (result == 0)
            
            if info["accessible"]:
                self._log(f"  ✓ {ws_url} - accessible", "success")
            else:
                self._log(f"  ✗ {ws_url} - not accessible", "warn")
        except Exception as e:
            info["accessible"] = False
            info["error"] = str(e)

        return info

    def _check_ws_vulns(self, ws_url: str, source_url: str) -> List[Dict]:
        """فحص ثغرات WebSocket"""
        vulns = []

        # 1) فحص لو مش secure (ws:// بدلاً من wss://)
        if ws_url.startswith("ws://"):
            vulns.append({
                "type": "ws_insecure",
                "severity": "medium",
                "url": ws_url,
                "title": "WebSocket غير مشفر (ws://)",
                "description": "استخدام ws:// بدلاً من wss:// - البيانات تنتقل بدون تشفير",
                "fix": "استخدم wss:// بدلاً من ws://",
            })
            self._log(f"  ⚠️  ws:// غير مشفر", "warn")

        # 2) محاولة WebSocket handshake للفحص Origin validation
        origin_vuln = self._check_origin_validation(ws_url)
        if origin_vuln:
            vulns.append(origin_vuln)

        return vulns

    def _check_origin_validation(self, ws_url: str) -> Optional[Dict]:
        """فحص Origin validation عبر WebSocket handshake"""
        try:
            parsed = urlparse(ws_url.replace("ws://", "http://").replace("wss://", "https://"))
            host = parsed.hostname
            port = parsed.port or (443 if ws_url.startswith("wss://") else 80)
            path = parsed.path or "/"

            # إنشاء WebSocket handshake مع Origin مزيف
            key = base64.b64encode(os.urandom(16)).decode()

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)

            if ws_url.startswith("wss://"):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))

            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Origin: https://evil.example.com\r\n"
                f"\r\n"
            )

            sock.send(handshake.encode())
            response = sock.recv(4096).decode("utf-8", errors="ignore")
            sock.close()

            # لو السيرفر قبل الاتصال (101 Switching Protocols) رغم الـ Origin المزيف
            if "101" in response and "Switching Protocols" in response:
                self._log(f"  ⚠️  WebSocket يقبل أي Origin (CSWSH)", "warn")
                return {
                    "type": "ws_origin_bypass",
                    "severity": "high",
                    "url": ws_url,
                    "title": "WebSocket Cross-Site Hijacking (CSWSH)",
                    "description": "الـ WebSocket يقبل اتصالات من أي Origin - يمكن استغلاله من مواقع أخرى",
                    "fix": "تحقق من Origin header في WebSocket handshake",
                }
            elif "403" in response or "401" in response:
                self._log(f"  ✓ WebSocket يرفض Origins غريبة", "success")
        except Exception as e:
            self._log(f"  لا يمكن فحص Origin: {e}", "warn")

        return None

    def _print_results(self, result: Dict):
        """عرض النتائج"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🔌 تقرير فحص WebSocket{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        if result["ws_endpoints"]:
            print(f"\n  {Colors.BOLD}WebSocket Endpoints ({len(result['ws_endpoints'])}):{Colors.NC}")
            for ws in result["ws_endpoints"]:
                secure = f"{Colors.GREEN}wss{Colors.NC}" if ws["secure"] else f"{Colors.RED}ws{Colors.NC}"
                status = f"{Colors.GREEN}✓{Colors.NC}" if ws["accessible"] else f"{Colors.RED}✗{Colors.NC}"
                print(f"    {status} {secure}://{ws['url'].split('://')[1][:50]}")

        if result["vulnerabilities"]:
            print(f"\n  {Colors.RED + Colors.BOLD}🚨 Vulnerabilities:{Colors.NC}")
            for v in result["vulnerabilities"]:
                sev_color = {
                    "high": Colors.RED,
                    "medium": Colors.YELLOW,
                }.get(v["severity"], Colors.NC)
                print(f"    {sev_color}[{v['severity'].upper()}]{Colors.NC} {v['title']}")
                print(f"      {fix_display(v['description'])}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - WebSocket Scanner")
    parser.add_argument("url", help="Target URL")
    args = parser.parse_args()

    scanner = WebSocketScanner()
    scanner.scan(args.url)
