#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Masquerade Engine
التنكر وتغيير الهوية - يجعل الأداة تبدو كـ browser حقيقي

الذكاء:
1. محاكاة browser حقيقي (headers, behavior, timing)
2. تبديل User-Agent دورياً
3. محاكاة human-like behavior (mouse, scroll)
4. تشويش الـ fingerprint
5. تجنب الـ patterns الملتوية
"""
import os
import sys
import time
import random
import json
import hashlib
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.arabic_display import SmartLogger, Colors, fix_display


# ============================ Browser Profiles ============================
BROWSER_PROFILES = [
    {
        "name": "Chrome Windows 10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
        },
        "timing": {"min_delay": 0.5, "max_delay": 2.0},
    },
    {
        "name": "Firefox Windows 10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Cache-Control": "no-cache",
            "Pragma": "no-cache",
            "Te": "trailers",
        },
        "timing": {"min_delay": 0.4, "max_delay": 1.8},
    },
    {
        "name": "Safari macOS",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "timing": {"min_delay": 0.6, "max_delay": 2.2},
    },
    {
        "name": "Chrome Linux",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "timing": {"min_delay": 0.3, "max_delay": 1.5},
    },
    {
        "name": "iPhone Safari",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "timing": {"min_delay": 0.7, "max_delay": 2.5},
    },
    {
        "name": "Android Chrome",
        "user_agent": "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "timing": {"min_delay": 0.5, "max_delay": 2.0},
    },
    {
        "name": "Edge Windows 10",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
        },
        "timing": {"min_delay": 0.4, "max_delay": 1.8},
    },
    {
        "name": "Googlebot",
        "user_agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "headers": {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "From": "googlebot(at)googlebot.com",
        },
        "timing": {"min_delay": 1.0, "max_delay": 3.0},
    },
]


# ============================ Masquerade Engine ============================
class MasqueradeEngine:
    """محرّك التنكر"""

    def __init__(self, http_client, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.current_profile: Optional[Dict] = None
        self.profiles_used: List[str] = []
        self.rotation_count = 0
        self.behavior_mode = "human"  # human / aggressive / stealth

        # إحصائيات
        self.detection_signals = 0
        self.last_detection = None

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[MASQUERADE] {msg}", level)

    # ============================ Profile Selection ============================
    def select_profile(self, profile_name: str = None) -> Dict:
        """اختيار profile"""
        if profile_name:
            for profile in BROWSER_PROFILES:
                if profile["name"] == profile_name:
                    self.current_profile = profile
                    self._apply_profile(profile)
                    return profile

        # اختيار عشوائي
        self.current_profile = random.choice(BROWSER_PROFILES)
        self._apply_profile(self.current_profile)
        self.profiles_used.append(self.current_profile["name"])
        self.rotation_count += 1

        self._log(f"تم تنكر الهوية: {self.current_profile['name']}", "info")
        return self.current_profile

    def _apply_profile(self, profile: Dict):
        """تطبيق profile على الـ client"""
        # تحديث User-Agent
        self.client.user_agent = profile["user_agent"]

        # تحديث delay لو محدد
        if "timing" in profile:
            timing = profile["timing"]
            self.client.delay = random.uniform(timing["min_delay"], timing["max_delay"])

    def rotate_profile(self) -> Dict:
        """تبديل profile"""
        old_profile = self.current_profile
        new_profile = self.select_profile()

        # نتأكد إنه مختلف
        attempts = 0
        while new_profile["name"] == (old_profile["name"] if old_profile else "") and attempts < 5:
            new_profile = self.select_profile()
            attempts += 1

        self._log(f"تم تبديل الهوية: {old_profile['name'] if old_profile else '?'} → {new_profile['name']}", "success")
        return new_profile

    # ============================ Behavior Simulation ============================
    def get_headers(self, url: str = None, referer: str = None) -> Dict:
        """الحصول على headers مناسبة"""
        if not self.current_profile:
            self.select_profile()

        headers = self.current_profile["headers"].copy()

        # إضافة Referer لو محدد
        if referer:
            headers["Referer"] = referer
        elif url:
            parsed = urlparse(url)
            headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"

        # إضافة DNT (Do Not Track) أحياناً
        if random.random() < 0.3:
            headers["DNT"] = "1"

        return headers

    def human_delay(self, base_delay: float = None):
        """تأخير يحاكي السلوك البشري"""
        if base_delay is None:
            if self.current_profile and "timing" in self.current_profile:
                timing = self.current_profile["timing"]
                delay = random.uniform(timing["min_delay"], timing["max_delay"])
            else:
                delay = random.uniform(0.5, 2.0)
        else:
            # تباين عشوائي حول الـ base delay
            delay = base_delay * random.uniform(0.5, 1.5)

        # لو mode=human، نضيف تباين أكبر
        if self.behavior_mode == "human":
            delay *= random.uniform(0.8, 1.3)

        time.sleep(delay)
        return delay

    def simulate_browsing_session(self, urls: List[str], callback=None):
        """محاكاة جلسة تصفح حقيقية"""
        self._log(f"محاكاة جلسة تصفح ({len(urls)} صفحات)", "info")

        for i, url in enumerate(urls):
            # تأخير قبل الطلب
            self.human_delay()

            # الحصول على headers
            headers = self.get_headers(url)
            if i > 0 and i < len(urls):
                # Referer = الصفحة السابقة
                headers["Referer"] = urls[i - 1]

            # تنفيذ الطلب
            resp = self.client.get(url, headers=headers)

            if callback:
                callback(resp)

            # أحياناً نسير للصفحة التالية بسرعة (محاكاة نقر سريع)
            if random.random() < 0.2:
                time.sleep(random.uniform(0.1, 0.3))
            else:
                self.human_delay()

            # تبديل profile أحياناً (محاكاة تبديل tab)
            if random.random() < 0.1:
                self.rotate_profile()

    # ============================ Fingerprint Evasion ============================
    def generate_fingerprint_noise(self) -> Dict:
        """توليد ضوضاء للـ fingerprint"""
        noise = {
            "screen_width": random.choice([1920, 1366, 1440, 1536, 1280]),
            "screen_height": random.choice([1080, 768, 900, 864, 720]),
            "color_depth": random.choice([24, 32]),
            "timezone": random.choice([
                "America/New_York", "Europe/London", "Asia/Tokyo",
                "Australia/Sydney", "Europe/Berlin", "America/Los_Angeles",
            ]),
            "language": random.choice(["en-US", "en-GB", "fr-FR", "de-DE", "es-ES"]),
            "platform": random.choice(["Win32", "MacIntel", "Linux x86_64"]),
            "cookies_enabled": True,
            "do_not_track": random.choice([None, "1", "0"]),
        }
        return noise

    # ============================ Detection Avoidance ============================
    def check_detection_signals(self, response: Dict) -> bool:
        """فحص إشارات الاكتشاف في الـ response"""
        detected = False

        # 1) Status codes تشير للحظر
        if response.get("status") in [403, 406, 418, 429]:
            detected = True
            self._log(f"إشارة اكتشاف: status {response['status']}", "warn")

        # 2) Body يحتوي على رسائل حظر
        body_lower = response.get("body", "").lower()
        block_indicators = [
            "blocked", "forbidden", "captcha", "verify you are human",
            "are you a robot", "access denied", "blocked by",
            "rate limit", "too many requests", "security check",
        ]

        for indicator in block_indicators:
            if indicator in body_lower:
                detected = True
                self._log(f"إشارة اكتشاف: '{indicator}' في response", "warn")
                break

        # 3) Headers تشير لـ WAF
        headers = response.get("headers", {})
        waf_headers = ["cf-mitigated", "x-waf", "x-blocked", "x-rate-limit"]
        for header in waf_headers:
            if header.lower() in {k.lower() for k in headers.keys()}:
                detected = True
                self._log(f"إشارة اكتشاف: header '{header}'", "warn")
                break

        if detected:
            self.detection_signals += 1
            self.last_detection = time.time()

        return detected

    def auto_evade(self, response: Dict) -> bool:
        """تنكر تلقائي عند الاكتشاف"""
        if self.check_detection_signals(response):
            self._log("تم الاكتشاف! تبديل الهوية...", "warn")

            # تبديل profile
            self.rotate_profile()

            # زيادة الـ delay
            self.client.delay = random.uniform(3.0, 7.0)

            return True

        return False

    # ============================ Stats ============================
    def get_stats(self) -> Dict:
        """إحصائيات"""
        return {
            "current_profile": self.current_profile["name"] if self.current_profile else None,
            "current_ua": self.current_profile["user_agent"][:50] + "..." if self.current_profile else None,
            "profiles_used": list(set(self.profiles_used)),
            "rotation_count": self.rotation_count,
            "detection_signals": self.detection_signals,
            "last_detection": self.last_detection,
            "behavior_mode": self.behavior_mode,
        }

    def set_behavior_mode(self, mode: str):
        """تحديد mode السلوك"""
        valid_modes = ["human", "aggressive", "stealth"]
        if mode in valid_modes:
            self.behavior_mode = mode
            self._log(f"تم تحديد mode السلوك: {mode}", "info")

            if mode == "stealth":
                self.client.delay = random.uniform(3.0, 7.0)
            elif mode == "aggressive":
                self.client.delay = random.uniform(0.1, 0.5)
            elif mode == "human":
                self.client.delay = random.uniform(0.5, 2.0)


# ============================ Test ============================
if __name__ == "__main__":
    from modules.http_client import HttpClient

    client = HttpClient(timeout=10)
    masquerade = MasqueradeEngine(client)

    print(f"\nاختيار profile...")
    profile = masquerade.select_profile()
    print(f"  Profile: {profile['name']}")
    print(f"  UA: {profile['user_agent'][:50]}...")

    print(f"\nتبديل profile...")
    new_profile = masquerade.rotate_profile()
    print(f"  New Profile: {new_profile['name']}")

    print(f"\nStats: {masquerade.get_stats()}")
