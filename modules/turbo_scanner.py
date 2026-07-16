#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostpwn - Turbo Scanner
فحص فائق السرعة - يجمع async engine + cache + smart scheduling

السرعة:
- async requests (50-100 متزامن)
- cache للنتائج المتكررة
- smart scheduling للمهام
- connection pooling
- result aggregation سريع
"""
import os
import sys
import time
from typing import Dict, List, Optional, Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.http_client import HttpClient
from modules.async_engine import AsyncEngine
from modules.cache_manager import CacheManager, HTTPResponseCache
from modules.smart_scheduler import SmartScheduler, TaskPriority
from modules.arabic_display import SmartLogger, Colors, fix_display
from modules.live_reporter import LiveReporter
from modules.vuln_database import VulnerabilityDatabase
from modules.component_analyzer import ComponentAnalyzer
from modules.adaptive_scanner import AdaptiveScanner
from modules.smart_waf import SmartWAFDetector
from modules.ai_reasoner import AIReasoner
from modules.zero_day_detector import ZeroDayDetector
from modules.real_ip_finder import RealIPFinder
from modules.vuln_generator import VulnerabilityGenerator
from modules.vuln_notifier import SmartNotifier


class TurboScanner:
    """فحص فائق السرعة - يجمع كل التقنيات"""

    def __init__(self, url: str, options: Dict = None):
        self.url = url
        self.options = options or {}

        # الإعداد
        self.client = HttpClient(
            timeout=self.options.get("timeout", 15),
            user_agent=self.options.get("user_agent", "ghostpwn/1.0"),
            proxy=self.options.get("proxy"),
            cookie=self.options.get("cookie"),
            delay=0,  # Turbo mode = no delay
        )

        # المحركات
        self.async_engine = AsyncEngine(
            self.client,
            max_workers=self.options.get("max_workers", 50),
            rate_limit=self.options.get("rate_limit", 100),
        )
        self.cache = CacheManager(max_size=1000, default_ttl=600)
        self.http_cache = HTTPResponseCache(self.cache)
        self.scheduler = SmartScheduler(max_workers=10)

        # الـ reporters
        self.reporter = LiveReporter()
        self.notifier = SmartNotifier()

        # النتائج
        self.all_vulns = []
        self.all_findings = []
        self.extra_data = {}

    def _log(self, msg, level="info"):
        getattr(self.reporter.logger, level, self.reporter.logger.info)(msg)

    def run(self) -> Dict:
        """تشغيل الفحص الفائق السرعة"""
        start_time = time.time()

        self._print_banner()

        # تعريف المهام
        self._define_tasks()

        # تشغيل الـ scheduler
        self.scheduler.run()

        # تجميع النتائج
        results = self._collect_results()

        # تقرير نهائي
        duration = time.time() - start_time
        self._print_final_report(duration, results)

        return results

    def _print_banner(self):
        """عرض banner"""
        print(f"\n{Colors.RED + Colors.BOLD}")
        print(f"  🚀 TURBO MODE - فحص فائق السرعة")
        print(f"{Colors.NC}")
        print(f"  {Colors.BOLD}الهدف:{Colors.NC} {self.url}")
        print(f"  {Colors.BOLD}Workers:{Colors.NC} {self.async_engine.max_workers}")
        print(f"  {Colors.BOLD}Rate:{Colors.NC} {self.async_engine.rate_limit} req/s")
        print(f"  {Colors.BOLD}Cache:{Colors.NC} {self.cache.max_size} entries")
        print()

    def _define_tasks(self):
        """تعريف مهام الفحص"""

        # Phase 1: Recon (CRITICAL - نبدأ بها)
        self.scheduler.add_task(
            "recon", "الاستطلاع",
            self._task_recon,
            priority=TaskPriority.CRITICAL,
        )

        # Phase 2: WAF Detection (HIGH - بعد Recon)
        self.scheduler.add_task(
            "waf_detect", "كشف WAF",
            self._task_waf_detection,
            priority=TaskPriority.HIGH,
            dependencies={"recon"},
        )

        # Phase 3: Real IP (HIGH - بالتوازي مع WAF)
        self.scheduler.add_task(
            "real_ip", "إيجاد الـ IP الحقيقي",
            self._task_real_ip,
            priority=TaskPriority.HIGH,
            dependencies={"recon"},
        )

        # Phase 4: Component Analysis (HIGH)
        self.scheduler.add_task(
            "components", "تحليل المكونات",
            self._task_component_analysis,
            priority=TaskPriority.HIGH,
            dependencies={"recon"},
        )

        # Phase 5: AI Analysis (MEDIUM - بالتوازي)
        self.scheduler.add_task(
            "ai_analysis", "التحليل الذكي",
            self._task_ai_analysis,
            priority=TaskPriority.MEDIUM,
            dependencies={"recon"},
        )

        # Phase 6: Vulnerability Scanning (MEDIUM)
        self.scheduler.add_task(
            "vuln_scan", "فحص الثغرات",
            self._task_vuln_scan,
            priority=TaskPriority.MEDIUM,
            dependencies={"waf_detect"},
        )

        # Phase 7: Zero-Day (LOW)
        self.scheduler.add_task(
            "zero_day", "كشف Zero-Day",
            self._task_zero_day,
            priority=TaskPriority.LOW,
            dependencies={"recon"},
        )

        # Phase 8: Vuln Generation (LOW)
        self.scheduler.add_task(
            "vuln_gen", "توليد الثغرات",
            self._task_vuln_generation,
            priority=TaskPriority.LOW,
            dependencies={"vuln_scan"},
        )

    # ============================ Tasks ============================
    def _task_recon(self) -> Dict:
        """الاستطلاع"""
        self._log("🔍 الاستطلاع...", "info")

        resp = self.client.get(self.url)
        if resp["status"] == 0:
            return {"error": "Connection failed"}

        # معلومات أساسية
        recon = {
            "status": resp["status"],
            "server": resp["headers"].get("Server", "Unknown"),
            "content_type": resp["headers"].get("Content-Type", "Unknown"),
            "body_size": len(resp["body"]),
            "headers": resp["headers"],
            "body": resp["body"][:5000],  # أول 5000 حرف
        }

        # فحص robots.txt و sitemap.xml (بالتوازي)
        paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]
        results = self.async_engine.scan_paths_concurrent(self.url, paths)

        for path, result in results.items():
            if result["response"] and result["response"]["status"] == 200:
                recon[f"has_{path.strip('/').replace('.', '_')}"] = True

        self.extra_data["recon"] = recon
        return recon

    def _task_waf_detection(self) -> Dict:
        """كشف WAF"""
        self._log("🛡️ كشف WAF...", "info")

        waf_detector = SmartWAFDetector(self.client)
        result = waf_detector.detect_waf(self.url)

        if result["detected"]:
            self.notifier.notify_vuln({
                "type": "waf_detected",
                "severity": "info",
                "title": f"WAF: {result['name']}",
                "url": self.url,
            })

        self.extra_data["waf"] = result
        return result

    def _task_real_ip(self) -> Dict:
        """إيجاد الـ IP الحقيقي"""
        self._log("🌐 إيجاد الـ IP الحقيقي...", "info")

        finder = RealIPFinder(self.client)
        result = finder.find_real_ip(self.url)

        if result.get("real_ip"):
            self.notifier.notify_vuln({
                "type": "real_ip_found",
                "severity": "high",
                "title": f"الـ IP الحقيقي: {result['real_ip']}",
                "url": self.url,
                "evidence": f"خلف CDN: {result.get('cdn_name', 'Unknown')}",
            })

        self.extra_data["real_ip"] = result
        return result

    def _task_component_analysis(self) -> Dict:
        """تحليل المكونات"""
        self._log("🔌 تحليل المكونات...", "info")

        analyzer = ComponentAnalyzer(self.client)
        result = analyzer.analyze(self.url)

        # إضافة الثغرات
        for vuln in result.get("vulnerabilities", []):
            self.all_vulns.append(vuln)
            self.notifier.notify_vuln(vuln)

        self.extra_data["components"] = result.get("components", {})
        return result

    def _task_ai_analysis(self) -> Dict:
        """التحليل الذكي"""
        self._log("🧠 التحليل الذكي...", "info")

        reasoner = AIReasoner(self.client)
        result = reasoner.analyze(self.url)

        self.extra_data["ai"] = result.get("behavior", {})
        return result

    def _task_vuln_scan(self) -> Dict:
        """فحص الثغرات"""
        self._log("🐛 فحص الثغرات...", "info")

        waf_detector = SmartWAFDetector(self.client)
        scanner = AdaptiveScanner(self.client, waf_detector, self.notifier)
        vulns = scanner.run_adaptive_scan(self.url)

        for vuln in vulns:
            self.all_vulns.append(vuln)
            self.notifier.notify_vuln(vuln)

        return {"vulns": vulns}

    def _task_zero_day(self) -> Dict:
        """كشف Zero-Day"""
        self._log("🔮 كشف Zero-Day...", "info")

        detector = ZeroDayDetector(self.client)
        result = detector.scan(self.url)

        for category, findings in result.items():
            for finding in findings:
                finding["category"] = category
                self.all_vulns.append(finding)
                self.notifier.notify_vuln(finding)

        return result

    def _task_vuln_generation(self) -> Dict:
        """توليد الثغرات"""
        self._log("🧬 توليد الثغرات...", "info")

        # الحصول على response
        resp = self.client.get(self.url)

        generator = VulnerabilityGenerator(self.client, notifier=self.notifier)
        vulns = generator.generate_from_response(self.url, resp)

        for vuln in vulns:
            self.all_vulns.append(vuln)
            self.notifier.notify_vuln(vuln, confidence=0.85)

        return {"generated": vulns}

    # ============================ Results ============================
    def _collect_results(self) -> Dict:
        """تجميع النتائج"""
        return {
            "url": self.url,
            "vulns": self.all_vulns,
            "extra_data": self.extra_data,
            "scheduler_stats": self.scheduler.get_stats(),
            "async_stats": self.async_engine.get_stats(),
            "cache_stats": self.cache.get_stats(),
        }

    def _print_final_report(self, duration: float, results: Dict):
        """عرض التقرير النهائي"""
        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")
        print(f"{Colors.MAGENTA}  🚀 تقرير الفحص الفائق السرعة{Colors.NC}")
        print(f"{Colors.MAGENTA}{'═'*60}{Colors.NC}")

        print(f"\n  {Colors.BOLD}⏱️  المدة الإجمالية:{Colors.NC} {duration:.1f}s")
        print(f"  {Colors.BOLD}🚨 الثغرات:{Colors.NC} {len(self.all_vulns)}")

        # إحصائيات السرعة
        async_stats = results["async_stats"]
        print(f"\n  {Colors.BOLD}📊 إحصائيات السرعة:{Colors.NC}")
        print(f"    الطلبات: {async_stats['total_requests']}")
        print(f"    السرعة: {async_stats['requests_per_second']:.1f} req/s")
        print(f"    معدل النجاح: {async_stats['success_rate']:.1f}%")

        # إحصائيات الـ cache
        cache_stats = results["cache_stats"]
        print(f"\n  {Colors.BOLD}💾 Cache:{Colors.NC}")
        print(f"    Hit Rate: {cache_stats['hit_rate']:.1f}%")
        print(f"    Size: {cache_stats['size']}/{cache_stats['max_size']}")

        # إحصائيات الـ scheduler
        sched_stats = results["scheduler_stats"]
        print(f"\n  {Colors.BOLD}📋 المهام:{Colors.NC}")
        print(f"    Completed: {sched_stats['completed']}/{sched_stats['total_tasks']}")
        print(f"    Success Rate: {sched_stats['success_rate']:.1f}%")

        # الثغرات حسب الخطورة
        if self.all_vulns:
            sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            for v in self.all_vulns:
                sev = v.get("severity", "info")
                if sev in sev_counts:
                    sev_counts[sev] += 1

            print(f"\n  {Colors.BOLD}📈 الثغرات حسب الخطورة:{Colors.NC}")
            for sev, count in sev_counts.items():
                if count > 0:
                    color = {
                        "critical": Colors.RED + Colors.BOLD,
                        "high": Colors.RED,
                        "medium": Colors.YELLOW,
                        "low": Colors.BLUE,
                        "info": Colors.GRAY,
                    }.get(sev, Colors.NC)
                    labels = {
                        "critical": "حرج",
                        "high": "عالي",
                        "medium": "متوسط",
                        "low": "منخفض",
                        "info": "معلومة",
                    }
                    print(f"    {color}{labels[sev]:8s}: {count} {'█'*count}{Colors.NC}")

        # الـ IP الحقيقي
        if self.extra_data.get("real_ip", {}).get("real_ip"):
            real_ip = self.extra_data["real_ip"]["real_ip"]
            print(f"\n  {Colors.GREEN + Colors.BOLD}🌐 الـ IP الحقيقي: {real_ip}{Colors.NC}")

        print(f"\n{Colors.MAGENTA}{'═'*60}{Colors.NC}")


def turbo_scan(url: str, options: Dict = None) -> Dict:
    """فحص فائق السرعة"""
    if not url.startswith("http"):
        url = "http://" + url

    scanner = TurboScanner(url, options or {})
    return scanner.run()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="ghostpwn - Turbo Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--workers", type=int, default=50, help="Max workers")
    parser.add_argument("--rate", type=int, default=100, help="Rate limit (req/s)")
    args = parser.parse_args()

    options = {
        "max_workers": args.workers,
        "rate_limit": args.rate,
    }

    result = turbo_scan(args.url, options)
