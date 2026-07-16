#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Cache Manager
تخزين مؤقت للطلبات والنتائج لتسريع الفحص

الميزات:
1. cache للـ HTTP responses
2. cache لنتائج DNS
3. cache لتحليل الـ patterns
4. TTL configurable
5. LRU eviction
6. Thread-safe
"""
import os
import sys
import time
import hashlib
import threading
import json
from typing import Dict, Optional, Any, List, Callable
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.arabic_display import SmartLogger, Colors


class CacheEntry:
    """عنصر في الـ cache"""
    def __init__(self, key: str, value: Any, ttl: int = 300):
        self.key = key
        self.value = value
        self.ttl = ttl
        self.created_at = time.time()
        self.accessed_at = time.time()
        self.access_count = 0

    def is_expired(self) -> bool:
        """فحص إذا انتهت صلاحية العنصر"""
        if self.ttl <= 0:
            return False
        return time.time() - self.created_at > self.ttl

    def touch(self):
        """تحديث وقت الوصول"""
        self.accessed_at = time.time()
        self.access_count += 1


class CacheManager:
    """مدير الـ cache"""

    def __init__(self, max_size: int = 1000, default_ttl: int = 300,
                 audit_logger=None):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.audit = audit_logger
        self.logger = SmartLogger()

        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.lock = threading.RLock()

        # إحصائيات
        self.stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0,
            "sets": 0,
        }

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)

    def _make_key(self, *args) -> str:
        """توليد مفتاح cache"""
        key_str = "|".join(str(a) for a in args)
        return hashlib.md5(key_str.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        """الحصول على عنصر من cache"""
        with self.lock:
            if key not in self.cache:
                self.stats["misses"] += 1
                return None

            entry = self.cache[key]

            if entry.is_expired():
                del self.cache[key]
                self.stats["misses"] += 1
                return None

            entry.touch()
            self.stats["hits"] += 1

            # تحريك للنهاية (LRU)
            self.cache.move_to_end(key)

            return entry.value

    def set(self, key: str, value: Any, ttl: int = None):
        """تخزين عنصر في cache"""
        with self.lock:
            if ttl is None:
                ttl = self.default_ttl

            # لو وصلنا للحد الأقصى، نحذف الأقدم
            while len(self.cache) >= self.max_size:
                oldest_key = next(iter(self.cache))
                del self.cache[oldest_key]
                self.stats["evictions"] += 1

            self.cache[key] = CacheEntry(key, value, ttl)
            self.stats["sets"] += 1

    def get_or_set(self, key: str, factory: Callable, ttl: int = None) -> Any:
        """الحصول من cache أو حساب وتخزين"""
        cached = self.get(key)
        if cached is not None:
            return cached

        value = factory()
        self.set(key, value, ttl)
        return value

    def invalidate(self, key: str):
        """إلغاء صلاحية عنصر"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]

    def clear(self):
        """مسح كل الـ cache"""
        with self.lock:
            self.cache.clear()

    def cleanup_expired(self) -> int:
        """تنظيف العناصر المنتهية"""
        with self.lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]

            for key in expired_keys:
                del self.cache[key]

            return len(expired_keys)

    def get_stats(self) -> Dict:
        """إحصائيات"""
        with self.lock:
            total_requests = self.stats["hits"] + self.stats["misses"]
            hit_rate = (self.stats["hits"] / total_requests * 100) if total_requests > 0 else 0

            return {
                **self.stats,
                "size": len(self.cache),
                "max_size": self.max_size,
                "hit_rate": hit_rate,
            }

    def print_stats(self):
        """عرض الإحصائيات"""
        stats = self.get_stats()
        print(f"\n  {Colors.CYAN}💾 Cache Stats:{Colors.NC}")
        print(f"    Size: {stats['size']}/{stats['max_size']}")
        print(f"    Hits: {stats['hits']}")
        print(f"    Misses: {stats['misses']}")
        print(f"    Hit Rate: {stats['hit_rate']:.1f}%")
        print(f"    Evictions: {stats['evictions']}")


# ============================ HTTP Response Cache ============================
class HTTPResponseCache:
    """cache خاص بـ HTTP responses"""

    def __init__(self, cache_manager: CacheManager = None):
        self.cache = cache_manager or CacheManager(max_size=500, default_ttl=600)

    def get_response(self, url: str, method: str = "GET") -> Optional[Dict]:
        """الحصول على response من cache"""
        key = self._make_key(url, method)
        return self.cache.get(key)

    def set_response(self, url: str, method: str, response: Dict, ttl: int = 600):
        """تخزين response في cache"""
        key = self._make_key(url, method)
        self.cache.set(key, response, ttl)

    def _make_key(self, url: str, method: str) -> str:
        return hashlib.md5(f"{method}|{url}".encode()).hexdigest()

    def get_or_fetch(self, url: str, method: str, fetch_func, ttl: int = 600) -> Dict:
        """الحصول من cache أو fetch"""
        cached = self.get_response(url, method)
        if cached:
            return cached

        response = fetch_func(url, method)
        self.set_response(url, method, response, ttl)
        return response


# ============================ DNS Cache ============================
class DNSCache:
    """cache خاص بـ DNS lookups"""

    def __init__(self, cache_manager: CacheManager = None):
        self.cache = cache_manager or CacheManager(max_size=200, default_ttl=3600)

    def get_ip(self, hostname: str) -> Optional[str]:
        """الحصول على IP من cache"""
        return self.cache.get(f"dns:{hostname}")

    def set_ip(self, hostname: str, ip: str):
        """تخزين IP في cache"""
        self.cache.set(f"dns:{hostname}", ip, ttl=3600)

    def get_or_resolve(self, hostname: str, resolve_func) -> str:
        """الحصول من cache أو resolve"""
        cached = self.get_ip(hostname)
        if cached:
            return cached

        ip = resolve_func(hostname)
        if ip:
            self.set_ip(hostname, ip)
        return ip
