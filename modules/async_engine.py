#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Async Engine
محرك طلبات متزامن (concurrent) - يجعل الفحص 10x أسرع

الذكاء:
1. Thread pool للطلبات المتزامنة
2. Connection reuse (keep-alive)
3. Request queuing ذكي
4. Rate limiting تكيّفي
5. Result aggregation
6. Error recovery
"""
import os
import sys
import time
import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Callable, Any, Tuple
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.arabic_display import SmartLogger, Colors, fix_display


class AsyncEngine:
    """محرك الطلبات المتزامنة"""

    def __init__(self, http_client: HttpClient = None, max_workers: int = 50,
                 rate_limit: int = 100, audit_logger=None):
        self.client = http_client or HttpClient(timeout=15)
        self.max_workers = max_workers
        self.rate_limit = rate_limit  # requests per second
        self.audit = audit_logger
        self.logger = SmartLogger()

        # Rate limiting
        self.request_times = []
        self.rate_lock = threading.Lock()

        # Stats
        self.stats = {
            "total_requests": 0,
            "successful": 0,
            "failed": 0,
            "cached": 0,
            "start_time": time.time(),
        }
        self.stats_lock = threading.Lock()

        # Results queue
        self.results_queue = queue.Queue()

        # Connection pool (simulated)
        self.connection_pool = {}
        self.pool_lock = threading.Lock()

    def _log(self, msg, level="info"):
        getattr(self.logger, level, self.logger.info)(msg)
        if self.audit:
            self.audit.log_event(f"[ASYNC] {msg}", level)

    def _wait_for_rate_limit(self):
        """احترام rate limit"""
        with self.rate_lock:
            now = time.time()
            # إزالة الطلبات الأقدم من ثانية
            self.request_times = [t for t in self.request_times if now - t < 1.0]

            if len(self.request_times) >= self.rate_limit:
                # انتظار
                sleep_time = 1.0 - (now - self.request_times[0])
                if sleep_time > 0:
                    time.sleep(sleep_time)

            self.request_times.append(now)

    def _make_request(self, url: str, method: str = "GET",
                      data=None, headers=None) -> Dict:
        """تنفيذ طلب واحد مع rate limiting"""
        self._wait_for_rate_limit()

        try:
            resp = self.client.request(url, method, data, headers)

            with self.stats_lock:
                self.stats["total_requests"] += 1
                if resp.get("status", 0) > 0:
                    self.stats["successful"] += 1
                else:
                    self.stats["failed"] += 1

            return {"url": url, "response": resp, "error": None}
        except Exception as e:
            with self.stats_lock:
                self.stats["total_requests"] += 1
                self.stats["failed"] += 1

            return {"url": url, "response": None, "error": str(e)}

    def fetch_multiple(self, urls: List[str], method: str = "GET",
                       callback: Callable = None) -> List[Dict]:
        """جلب عدة URLs في نفس الوقت"""
        self._log(f"جلب {len(urls)} URL بصورة متزامنة ({self.max_workers} workers)...", "info")

        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._make_request, url, method): url for url in urls}

            for future in as_completed(futures):
                result = future.result()
                results.append(result)

                if callback:
                    callback(result)

                self.results_queue.put(result)

        self._log(f"اكتمل: {len(results)} طلب", "success")
        return results

    def fetch_with_payloads(self, base_url: str, param: str,
                            payloads: List[str], method: str = "GET") -> List[Dict]:
        """جلب عدة payloads على نفس URL بصورة متزامنة"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(base_url)
        base_params = parse_qs(parsed.query) if parsed.query else {}

        # بناء URLs لكل payload
        urls = []
        for payload in payloads:
            test_params = base_params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                  parsed.params, new_query, parsed.fragment))
            urls.append(test_url)

        return self.fetch_multiple(urls, method)

    def scan_paths_concurrent(self, base_url: str, paths: List[str],
                              method: str = "GET") -> Dict[str, Dict]:
        """فحص عدة مسارات في نفس الوقت"""
        urls = [base_url.rstrip("/") + path for path in paths]
        results = self.fetch_multiple(urls, method)

        # تنظيم النتائج حسب path
        path_results = {}
        for result in results:
            url = result["url"]
            path = url.replace(base_url.rstrip(""), "")
            path_results[path] = result

        return path_results

    def brute_force_concurrent(self, host: str, port: int,
                               credentials: List[Tuple[str, str]],
                               check_func: Callable) -> Optional[Dict]:
        """brute force متزامن"""
        self._log(f"Brute force متزامن: {len(credentials)} محاولة", "info")

        with ThreadPoolExecutor(max_workers=min(self.max_workers, 20)) as executor:
            futures = {
                executor.submit(check_func, host, port, user, passw): (user, passw)
                for user, passw in credentials
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    self._log(f"نجح: {result}", "success")
                    return result

        return None

    def parallel_scan(self, targets: List[str], scan_func: Callable,
                      progress_callback: Callable = None) -> List[Dict]:
        """فحص عدة أهداف في نفس الوقت"""
        self._log(f"فحص {len(targets)} هدف بصورة متزامنة", "info")

        results = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(scan_func, target): target for target in targets}

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append({"target": futures[future], "result": result})
                except Exception as e:
                    results.append({"target": futures[future], "error": str(e)})

                completed += 1
                if progress_callback:
                    progress_callback(completed, len(targets))

        return results

    def batch_request_with_strategy(self, urls: List[str],
                                    strategy: str = "balanced") -> List[Dict]:
        """طلبات بناءً على استراتيجية"""
        strategies = {
            "stealth": {"workers": 5, "rate": 10},
            "balanced": {"workers": 20, "rate": 50},
            "aggressive": {"workers": 50, "rate": 200},
            "turbo": {"workers": 100, "rate": 500},
        }

        config = strategies.get(strategy, strategies["balanced"])

        old_workers = self.max_workers
        old_rate = self.rate_limit

        self.max_workers = config["workers"]
        self.rate_limit = config["rate"]

        self._log(f"استراتيجية: {strategy} ({config['workers']} workers, {config['rate']} req/s)", "info")

        results = self.fetch_multiple(urls)

        # استرجاع الإعدادات
        self.max_workers = old_workers
        self.rate_limit = old_rate

        return results

    def get_stats(self) -> Dict:
        """إحصائيات"""
        elapsed = time.time() - self.stats["start_time"]
        with self.stats_lock:
            stats = self.stats.copy()

        stats["elapsed"] = elapsed
        stats["requests_per_second"] = stats["total_requests"] / elapsed if elapsed > 0 else 0
        stats["success_rate"] = (
            (stats["successful"] / stats["total_requests"] * 100)
            if stats["total_requests"] > 0 else 0
        )

        return stats

    def print_stats(self):
        """عرض الإحصائيات"""
        stats = self.get_stats()
        elapsed = stats["elapsed"]
        rps = stats["requests_per_second"]

        print(f"\n  {Colors.CYAN}📊 Async Engine Stats:{Colors.NC}")
        print(f"    الوقت: {elapsed:.1f}s")
        print(f"    الطلبات: {stats['total_requests']}")
        print(f"    النجاح: {stats['successful']}")
        print(f"    الفشل: {stats['failed']}")
        print(f"    السرعة: {rps:.1f} req/s")
        print(f"    معدل النجاح: {stats['success_rate']:.1f}%")
