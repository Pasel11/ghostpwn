#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Stealth Mode
فحص صامت ومنخفض الضجيج - لتقليل كشف الـ SIEM/IDS
"""
import sys
import os
import time
import random
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class StealthMode:
    """فحص صامت - لتجنب كشف الـ IDS/SIEM"""

    def __init__(self, http_client, audit_logger=None):
        self.client = http_client
        self.audit = audit_logger
        self.original_delay = http_client.delay
        self.original_user_agent = http_client.user_agent

    def enable(self, level: str = "medium"):
        """تفعيل وضع التخفي

        Levels:
        - low:      تأخير 0.5s + UA عشوائي
        - medium:   تأخير 1-3s + UA عشوائي + payloads محدودة
        - high:     تأخير 3-7s + UA عشوائي + بطيء جداً
        """
        if self.audit:
            self.audit.log_event(f"Enabling stealth mode: {level}", "info")

        if level == "low":
            self.client.delay = 0.5
        elif level == "medium":
            self.client.delay = random.uniform(1, 3)
        elif level == "high":
            self.client.delay = random.uniform(3, 7)

        # UA عشوائي
        self.client.user_agent = self._random_user_agent()

        if self.audit:
            self.audit.log_event(f"Stealth: delay={self.client.delay}s, UA={self.client.user_agent}", "info")

    def disable(self):
        """إيقاف وضع التخفي"""
        self.client.delay = self.original_delay
        self.client.user_agent = self.original_user_agent

        if self.audit:
            self.audit.log_event("Stealth mode disabled", "info")

    def _random_user_agent(self) -> str:
        """توليد User-Agent عشوائي"""
        uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        ]
        return random.choice(uas)

    def slow_request(self, url: str, method: str = "GET") -> dict:
        """طلب صامت بـ delay عشوائي"""
        # delay عشوائي إضافي
        extra_delay = random.uniform(0.5, 2.0)
        time.sleep(extra_delay)

        return self.client.request(url, method)

    def rotate_user_agent(self):
        """تغيير الـ User-Agent عشوائياً"""
        self.client.user_agent = self._random_user_agent()
        if self.audit:
            self.audit.log_event(f"Rotated UA: {self.client.user_agent}", "info")

    def random_delay(self, min_sec: float = 1.0, max_sec: float = 5.0):
        """تأخير عشوائي"""
        delay = random.uniform(min_sec, max_sec)
        time.sleep(delay)
        if self.audit:
            self.audit.log_event(f"Random delay: {delay:.2f}s", "info")
