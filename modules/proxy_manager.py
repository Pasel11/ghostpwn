#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Proxy Manager
إدارة proxies وتغيير الـ IP تلقائياً

ميزات:
1. قائمة proxies مجانية (تجمع تلقائياً)
2. تبديل تلقائي عند الاكتشاف
3. دعم Tor SOCKS proxy
4. فحص صحة الـ proxies
5. rotation ذكي
"""
import os
import sys
import time
import json
import socket
import random
import urllib.request
import urllib.parse
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Free Proxy Sources ============================
FREE_PROXY_SOURCES = [
    # قائمة proxies مجانية (static backup)
    # هذه proxies عامة - قد تكون بطيئة أو غير موثوقة
    # للأداء الحقيقي استخدم VPN أو proxies مدفوعة
]


# قائمة proxies احتياطية (static)
BACKUP_PROXIES = [
    # HTTP proxies (هذه أمثلة - قد لا تعمل)
    # للأداء الحقيقي استخدم VPN/Tor أو proxies مدفوعة
]


# ============================ Proxy Manager ============================
class ProxyManager:
    """إدارة الـ proxies"""

    def __init__(self, audit_logger=None):
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.proxies: List[Dict] = []
        self.current_proxy: Optional[Dict] = None
        self.current_index = 0

        # إحصائيات
        self.rotation_count = 0
        self.failed_proxies = set()

        # حالة التنكر
        self.masquerade_active = False
        self.detection_count = 0
        self.detection_threshold = 3  # لو 3 detections = نغير الـ proxy

        # Tor support
        self.tor_available = self._check_tor()
        self.tor_port = 9050  # default Tor SOCKS port

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[PROXY] {msg}", level)

    def _check_tor(self) -> bool:
        """فحص إذا كان Tor متاح"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", 9050))
            sock.close()
            if result == 0:
                self._log("Tor SOCKS proxy متاح على port 9050", "success")
                return True
        except Exception:
            pass
        return False

    # ============================ Load Proxies ============================
    def load_proxies_from_file(self, file_path: str) -> int:
        """تحميل proxies من ملف"""
        loaded = 0
        try:
            with open(file_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # تنسيقات مدعومة:
                    # ip:port
                    # http://ip:port
                    # socks5://ip:port
                    # ip:port:user:pass
                    proxy = self._parse_proxy(line)
                    if proxy:
                        self.proxies.append(proxy)
                        loaded += 1

            self._log(f"تم تحميل {loaded} proxy من {file_path}", "success")
        except Exception as e:
            self._log(f"فشل تحميل proxies: {e}", "error")

        return loaded

    def _parse_proxy(self, line: str) -> Optional[Dict]:
        """تحليل سطر proxy"""
        try:
            if line.startswith("socks5://"):
                url = line
                proxy_type = "socks5"
            elif line.startswith("socks4://"):
                url = line
                proxy_type = "socks4"
            elif line.startswith("http://") or line.startswith("https://"):
                url = line
                proxy_type = "http"
            else:
                # ip:port format
                if ":" in line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        url = f"http://{parts[0]}:{parts[1]}"
                        proxy_type = "http"
                    elif len(parts) == 4:
                        # ip:port:user:pass
                        url = f"http://{parts[0]}:{parts[1]}"
                        proxy_type = "http"
                        return {
                            "url": url,
                            "type": proxy_type,
                            "auth": (parts[2], parts[3]),
                            "healthy": True,
                            "failures": 0,
                        }
                    else:
                        return None
                else:
                    return None

            return {
                "url": url,
                "type": proxy_type,
                "auth": None,
                "healthy": True,
                "failures": 0,
            }
        except Exception:
            return None

    def add_proxy(self, proxy_url: str, proxy_type: str = "http",
                  auth: Tuple[str, str] = None) -> bool:
        """إضافة proxy"""
        proxy = {
            "url": proxy_url,
            "type": proxy_type,
            "auth": auth,
            "healthy": True,
            "failures": 0,
        }
        self.proxies.append(proxy)
        self._log(f"تم إضافة proxy: {proxy_url}", "info")
        return True

    # ============================ Get Current IP ============================
    def get_current_ip(self) -> Optional[str]:
        """الحصول على الـ IP الحالي"""
        try:
            # محاولة عبر IP API
            req = urllib.request.Request("https://api.ipify.org?format=text",
                                         headers={"User-Agent": "ghostpwn"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.read().decode().strip()
        except Exception:
            try:
                req = urllib.request.Request("https://httpbin.org/ip",
                                             headers={"User-Agent": "ghostpwn"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    return data.get("origin", "").split(",")[0]
            except Exception:
                return None

    def get_proxy_ip(self, proxy: Dict) -> Optional[str]:
        """الحصول على IP الـ proxy"""
        try:
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy["url"],
                "https": proxy["url"],
            })
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request("https://api.ipify.org?format=text",
                                         headers={"User-Agent": "ghostpwn"})
            with opener.open(req, timeout=10) as resp:
                return resp.read().decode().strip()
        except Exception:
            return None

    # ============================ Test Proxy ============================
    def test_proxy(self, proxy: Dict, test_url: str = "https://httpbin.org/ip") -> bool:
        """فحص صحة proxy"""
        try:
            start = time.time()
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy["url"],
                "https": proxy["url"],
            })
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(test_url,
                                         headers={"User-Agent": "ghostpwn"})
            with opener.open(req, timeout=15) as resp:
                elapsed = time.time() - start
                if resp.getcode() == 200:
                    proxy["healthy"] = True
                    proxy["failures"] = 0
                    proxy["latency"] = elapsed
                    return True
        except Exception:
            proxy["failures"] = proxy.get("failures", 0) + 1
            if proxy["failures"] >= 3:
                proxy["healthy"] = False

        return False

    def test_all_proxies(self) -> int:
        """فحص كل الـ proxies"""
        self._log(f"فحص {len(self.proxies)} proxy...", "info")

        healthy = 0
        for proxy in self.proxies:
            if self.test_proxy(proxy):
                healthy += 1
                self._log(f"  ✓ {proxy['url']} ({proxy.get('latency', 0):.1f}s)", "success")
            else:
                self._log(f"  ✗ {proxy['url']}", "warn")

        self._log(f"{healthy}/{len(self.proxies)} proxies صحية", "info")
        return healthy

    # ============================ Get Next Proxy ============================
    def get_next_proxy(self) -> Optional[Dict]:
        """الحصول على الـ proxy التالي"""
        if not self.proxies:
            return None

        # البحث عن proxy صحي
        healthy_proxies = [p for p in self.proxies if p.get("healthy", True)]
        if not healthy_proxies:
            self._log("لا توجد proxies صحية!", "error")
            return None

        # rotation
        self.current_index = (self.current_index + 1) % len(healthy_proxies)
        self.current_proxy = healthy_proxies[self.current_index]
        self.rotation_count += 1

        # الحصول على IP الـ proxy
        proxy_ip = self.get_proxy_ip(self.current_proxy)
        self.current_proxy["ip"] = proxy_ip

        self._log(f"تم التبديل لـ proxy: {self.current_proxy['url']} (IP: {proxy_ip})", "success")
        return self.current_proxy

    def get_proxy_for_urllib(self) -> Optional[Dict]:
        """الحصول على proxy بصيغة urllib"""
        if not self.current_proxy:
            self.get_next_proxy()

        if not self.current_proxy:
            return None

        proxy_url = self.current_proxy["url"]
        if self.current_proxy.get("auth"):
            # إضافة auth للـ URL
            user, passw = self.current_proxy["auth"]
            # proxy_url format: http://user:pass@ip:port
            parsed = urllib.parse.urlparse(proxy_url)
            proxy_url = f"{parsed.scheme}://{user}:{passw}@{parsed.netloc}"

        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    # ============================ Tor Support ============================
    def use_tor(self) -> bool:
        """استخدام Tor كـ proxy"""
        if not self.tor_available:
            self._log("Tor غير متاح - شغّل Tor service", "error")
            self._log("  apt install tor && service tor start", "info")
            return False

        self.current_proxy = {
            "url": f"socks5://127.0.0.1:{self.tor_port}",
            "type": "socks5",
            "auth": None,
            "healthy": True,
            "failures": 0,
            "is_tor": True,
        }

        self._log("تم التفعيل: Tor SOCKS proxy", "success")
        self._log("  الـ IP اﻷن مخفي عبر Tor", "info")
        return True

    def renew_tor_identity(self) -> bool:
        """تجديد هوية Tor (IP جديد)"""
        if not self.tor_available:
            return False

        try:
            # إرسال signal لـ Tor controller
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect(("127.0.0.1", 9051))  # Tor control port

            # مصادقة
            sock.send(b"AUTHENTICATE \"\"\r\n")
            resp = sock.recv(1024)
            if b"250" not in resp:
                sock.close()
                return False

            # طلب NEWNYM (هوية جديدة)
            sock.send(b"SIGNAL NEWNYM\r\n")
            resp = sock.recv(1024)
            sock.close()

            if b"250" in resp:
                self._log("تم تجديد هوية Tor - IP جديد", "success")
                time.sleep(3)  # انتظار قليل للـ Tor
                return True
        except Exception as e:
            self._log(f"فشل تجديد هوية Tor: {e}", "error")

        return False

    # ============================ Detection Handling ============================
    def report_detection(self, detection_type: str = "unknown"):
        """الإبلاغ عن اكتشاف"""
        self.detection_count += 1
        self._log(f"اكتشاف #{self.detection_count}: {detection_type}", "warn")

        if self.detection_count >= self.detection_threshold:
            self._log("تم تجاوز حد الاكتشاف - تبديل الـ IP", "warn")
            self.rotate_ip()

    def rotate_ip(self) -> bool:
        """تبديل الـ IP"""
        self._log("تبديل الـ IP...", "info")

        # لو Tor متاح، نجدده
        if self.current_proxy and self.current_proxy.get("is_tor"):
            return self.renew_tor_identity()

        # لو عندنا proxies، نبدل
        if self.proxies:
            old_proxy = self.current_proxy
            new_proxy = self.get_next_proxy()

            if new_proxy and new_proxy != old_proxy:
                self._log(f"تم التبديل من {old_proxy.get('ip', '?')} إلى {new_proxy.get('ip', '?')}", "success")
                self.detection_count = 0  # reset
                return True

        # لو مفيش، نوصي بـ VPN
        self._log("لا توجد proxies متاحة - استخدم VPN أو Tor", "warn")
        self._log("  لتفعيل Tor: apt install tor && service tor start", "info")
        return False

    # ============================ Stats ============================
    def get_stats(self) -> Dict:
        """إحصائيات"""
        return {
            "total_proxies": len(self.proxies),
            "healthy_proxies": sum(1 for p in self.proxies if p.get("healthy", True)),
            "current_proxy": self.current_proxy["url"] if self.current_proxy else None,
            "current_ip": self.current_proxy.get("ip") if self.current_proxy else None,
            "rotation_count": self.rotation_count,
            "detection_count": self.detection_count,
            "tor_available": self.tor_available,
            "tor_active": bool(self.current_proxy and self.current_proxy.get("is_tor")),
        }


# ============================ Test ============================
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Proxy Manager")
    parser.add_argument("--check-ip", action="store_true", help="Check current IP")
    parser.add_argument("--tor", action="store_true", help="Use Tor")
    parser.add_argument("--renew-tor", action="store_true", help="Renew Tor identity")
    parser.add_argument("--load", help="Load proxies from file")
    parser.add_argument("--add", help="Add proxy (ip:port)")
    parser.add_argument("--test", action="store_true", help="Test all proxies")
    parser.add_argument("--stats", action="store_true", help="Show stats")
    args = parser.parse_args()

    pm = ProxyManager()

    if args.check_ip:
        ip = pm.get_current_ip()
        print(f"Current IP: {ip}")

    elif args.tor:
        if pm.use_tor():
            ip = pm.get_proxy_ip(pm.current_proxy)
            print(f"Tor IP: {ip}")

    elif args.renew_tor:
        pm.renew_tor_identity()

    elif args.load:
        pm.load_proxies_from_file(args.load)

    elif args.add:
        pm.add_proxy(f"http://{args.add}")

    elif args.test:
        pm.test_all_proxies()

    elif args.stats:
        print(json.dumps(pm.get_stats(), indent=2))

    else:
        parser.print_help()
